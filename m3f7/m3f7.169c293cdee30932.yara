
rule m3f7_169c293cdee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.169c293cdee30932"
     cluster="m3f7.169c293cdee30932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['2114b93852e21786d1813a4b04ecc85e','5c66d79b175491cf2a57773557bc064c','ff0d2643bcb58d0f7058085e4e7f27cb']"

   strings:
      $hex_string = { 6465723a3070783b22207372633d22687474703a2f2f312e62702e626c6f6773706f742e636f6d2f2d4f6270595a77614c697a492f545a38677643706d436a49 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
