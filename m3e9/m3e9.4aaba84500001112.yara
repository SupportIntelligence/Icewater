
rule m3e9_4aaba84500001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4aaba84500001112"
     cluster="m3e9.4aaba84500001112"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vilsel malicious pworm"
     md5_hashes="['00241eeb0944b34819143b8750d1a3d9','3886b302b5c72adc91de54783cfd152a','b3724ba9ddf2816e67ef13245223bfdd']"

   strings:
      $hex_string = { 74d5ffff66cdf9ff49bdecff33b0e2ff169fd6ff0092ccff007caef3015f84df013c54c6021d27af03030398030303860202026e020202580000003c0000001b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
