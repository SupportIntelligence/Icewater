
rule m2319_2995099dea208912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2995099dea208912"
     cluster="m2319.2995099dea208912"
     cluster_size="10"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink script html"
     md5_hashes="['086217c740071c91b402ee5bdf4222a0','5e2d25c31b27096a3e6a9ab5eb2e0ebc','f98ecdc7cabb7ba9dfb0b30409c34b67']"

   strings:
      $hex_string = { 726f77436c6173732c27223e2026233138373b3c2f7370616e3e275d2e6a6f696e28272729292c0d0a0909096f766572203d2066756e6374696f6e28297b0d0a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
