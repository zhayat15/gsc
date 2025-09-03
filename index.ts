import { createClient } from 'npm:@supabase/supabase-js@2.56.0';
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'
};
// Simple JWT implementation for Google API authentication
class SimpleJWT {
  credentials;
  constructor(credentials){
    this.credentials = credentials;
  }
  async getAccessToken() {
    const now = Math.floor(Date.now() / 1000);
    const expiry = now + 3600; // 1 hour
    // Create JWT header
    const header = {
      alg: 'RS256',
      typ: 'JWT'
    };
    // Create JWT payload
    const payload = {
      iss: this.credentials.client_email,
      scope: 'https://www.googleapis.com/auth/webmasters.readonly',
      aud: 'https://oauth2.googleapis.com/token',
      exp: expiry,
      iat: now
    };
    // Encode header and payload
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    // Create signature
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    // Import the private key
    const privateKey = await crypto.subtle.importKey('pkcs8', this.pemToArrayBuffer(this.credentials.private_key), {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    }, false, [
      'sign'
    ]);
    // Sign the JWT
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(signatureInput));
    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const jwt = `${signatureInput}.${encodedSignature}`;
    // Exchange JWT for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt
      })
    });
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      throw new Error(`Token exchange failed: ${tokenResponse.status} ${errorText}`);
    }
    const tokenData = await tokenResponse.json();
    return tokenData.access_token;
  }
  pemToArrayBuffer(pem) {
    const pemContents = pem.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').replace(/\s/g, '');
    console.log('DEBUG: pemContents (after stripping headers and whitespace):', pemContents);
    console.log('DEBUG: pemContents length:', pemContents.length);
    let binaryString;
    try {
      binaryString = atob(pemContents);
      console.log('DEBUG: binaryString (after atob) length:', binaryString.length);
      console.log('DEBUG: Successfully decoded base64');
    } catch (e) {
      console.error('ERROR: Failed to decode base64 with atob:', e);
      console.error('ERROR: pemContents that failed:', pemContents.substring(0, 100) + '...');
      throw new Error('Failed to decode base64: ' + e.message);
    }
    const bytes = new Uint8Array(binaryString.length);
    for(let i = 0; i < binaryString.length; i++){
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
Deno.serve(async (req)=>{
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: corsHeaders
    });
  }
  try {
    // Initialize Supabase client
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    const supabase = createClient(supabaseUrl, supabaseServiceKey);
    // Get GSC Service Account Key from environment variables
    const gscServiceAccountKey = Deno.env.get('GSC_SERVICE_ACCOUNT_KEY');
    if (!gscServiceAccountKey) {
      throw new Error('GSC_SERVICE_ACCOUNT_KEY not found in environment variables. Please add your service account JSON as a Supabase secret.');
    }
    // Parse the service account key JSON string
    let credentials;
    try {
      credentials = JSON.parse(gscServiceAccountKey);
    } catch (parseError) {
      throw new Error('Invalid GSC_SERVICE_ACCOUNT_KEY format. Please ensure it\'s a valid JSON string.');
    }
    // Validate required fields in credentials
    if (!credentials.client_email || !credentials.private_key) {
      throw new Error('Invalid service account credentials. Missing client_email or private_key.');
    }
    // Parse request body
    const { siteUrl, startDate, endDate, dimensions = [
      'query'
    ], rowLimit = 1000 } = await req.json();
    if (!siteUrl || !startDate || !endDate) {
      return new Response(JSON.stringify({
        success: false,
        error: 'siteUrl, startDate, and endDate are required',
        example: {
          siteUrl: 'https://a1skinclinic.com.au/',
          startDate: '2024-12-01',
          endDate: '2024-12-31'
        }
      }), {
        status: 400,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json'
        }
      });
    }
    // Initialize JWT client for Google API authentication
    const jwtClient = new SimpleJWT(credentials);
    // Get access token
    const accessToken = await jwtClient.getAccessToken();
    // Construct GSC API request body
    const gscApiRequestBody = {
      startDate,
      endDate,
      dimensions,
      rowLimit,
      startRow: 0
    };
    console.log('Making GSC API request for:', siteUrl, 'from', startDate, 'to', endDate);
    // Make request to GSC API
    const gscApiResponse = await fetch(`https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(gscApiRequestBody)
    });
    if (!gscApiResponse.ok) {
      const errorText = await gscApiResponse.text();
      console.error('GSC API Error:', errorText);
      if (gscApiResponse.status === 403) {
        throw new Error('Access denied to GSC property. Please ensure the service account is added as a user in Google Search Console.');
      }
      throw new Error(`GSC API request failed: ${gscApiResponse.status} ${errorText}`);
    }
    const gscData = await gscApiResponse.json();
    const rows = gscData.rows || [];
    console.log(`Received ${rows.length} rows from GSC API`);
    // Prepare data for batch insert into Supabase
    const dataToInsert = rows.map((row)=>{
      const record = {
        site_url: siteUrl,
        clicks: row.clicks || 0,
        impressions: row.impressions || 0,
        ctr: row.ctr || 0,
        position: row.position || 0,
        date: startDate,
        dimension_type: dimensions.join(','),
        created_at: new Date().toISOString()
      };
      // Map dimensions to appropriate fields
      dimensions.forEach((dimension, index)=>{
        const value = row.keys[index];
        switch(dimension){
          case 'query':
            record.query = value;
            break;
          case 'page':
            record.page = value;
            break;
          case 'device':
            record.device = value;
            break;
          case 'country':
            record.country = value;
            break;
        }
      });
      return record;
    });
    // Insert data into gsc_performance_data table
    if (dataToInsert.length > 0) {
      // Delete existing data for the same site, date range, and dimensions to prevent duplicates
      const { error: deleteError } = await supabase.from('gsc_performance_data').delete().eq('site_url', siteUrl).eq('date', startDate).eq('dimension_type', dimensions.join(','));
      if (deleteError) {
        console.warn('Warning: Could not delete existing data:', deleteError);
      }
      // Insert new data
      const { error: insertError } = await supabase.from('gsc_performance_data').insert(dataToInsert);
      if (insertError) {
        console.error('Supabase insert error:', insertError);
        throw new Error(`Failed to save GSC data to database: ${insertError.message}`);
      }
      // Update last sync time for the site
      await supabase.from('gsc_sites').upsert({
        site_url: siteUrl,
        display_name: siteUrl.replace(/https?:\/\//, '').replace(/\/$/, ''),
        verification_status: 'verified',
        last_sync: new Date().toISOString(),
        active: true
      });
    }
    // Calculate summary metrics
    const totalClicks = rows.reduce((sum, row)=>sum + (row.clicks || 0), 0);
    const totalImpressions = rows.reduce((sum, row)=>sum + (row.impressions || 0), 0);
    const avgCTR = totalImpressions > 0 ? totalClicks / totalImpressions * 100 : 0;
    const avgPosition = rows.length > 0 ? rows.reduce((sum, row)=>sum + (row.position || 0), 0) / rows.length : 0;
    return new Response(JSON.stringify({
      success: true,
      message: `Successfully fetched and stored ${rows.length} GSC data rows`,
      data: {
        rowCount: rows.length,
        dateRange: {
          startDate,
          endDate
        },
        summary: {
          totalClicks,
          totalImpressions,
          avgCTR: Math.round(avgCTR * 100) / 100,
          avgPosition: Math.round(avgPosition * 100) / 100
        },
        sampleRows: rows.slice(0, 5) // Return first 5 rows as sample
      }
    }), {
      status: 200,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json'
      }
    });
  } catch (error) {
    console.error('Edge Function error:', error);
    return new Response(JSON.stringify({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      timestamp: new Date().toISOString()
    }), {
      status: 500,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json'
      }
    });
  }
});
