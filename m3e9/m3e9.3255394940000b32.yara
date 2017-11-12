
rule m3e9_3255394940000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3255394940000b32"
     cluster="m3e9.3255394940000b32"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['089028f0c554056eb2dc6076122680a6','0cdf76f3418f5af82471728b0ff719c5','862ae2858bdae38dd285d3b3ccde3fa8']"

   strings:
      $hex_string = { b3b4ca0d1a160c0f2b312e2c2a3032302a2608000000f66b4864a1d40303cca4ccf4eaebd7637292b8d7d0d3d4d7c3c4b2b3c7060f141b110e121b2531333734 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
