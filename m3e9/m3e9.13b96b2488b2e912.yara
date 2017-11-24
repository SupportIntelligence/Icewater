
rule m3e9_13b96b2488b2e912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b96b2488b2e912"
     cluster="m3e9.13b96b2488b2e912"
     cluster_size="157"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic gepys kryptik"
     md5_hashes="['0196812a31c77c119701d32b72d6c66e','0c44ed03038589a97fa47fd9e010d1cd','473a3beceb859bb15d13ac9170f64ce4']"

   strings:
      $hex_string = { caf7844f6e9b7c91b4d1746ccdf66c90d9f26494d5ee5c99deeb549ddae74ca1e6e344a5e2df3c89aedb348daad72c5aa7d824e6b2d41cf2aed0140ebbcc0c9a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
