
rule m3e9_65146e39c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65146e39c8800932"
     cluster="m3e9.65146e39c8800932"
     cluster_size="47"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['28513714e398c7c8ca9237e39374f474','31c3c2354f0cb74dc5541145861b3676','b05a894ce4960140e8785d017018b105']"

   strings:
      $hex_string = { 5555525560606e7d8a8a625c616f989cd2f9fffffffbfbaf000000f4fffd2e0714171514140a0b1d534c5566665955615b4c7e8c8d8f909d9f9fa39ea0def1fa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
