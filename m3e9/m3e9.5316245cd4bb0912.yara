
rule m3e9_5316245cd4bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5316245cd4bb0912"
     cluster="m3e9.5316245cd4bb0912"
     cluster_size="115"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus svvqzfhi jorik"
     md5_hashes="['0f409527afab3815b45bd76876943f25','1ba6161c0655df364bde78ff799b0093','86f6589bda86172e999de9aa065fc06d']"

   strings:
      $hex_string = { 3af0fe2600fbefe0fe603178ff2f64ff36080024ff14ff00ffe0fe000df3b9022b3aff0a030004001eb808000e6c44fff504000000c71ce7050011f47bfbfd23 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
