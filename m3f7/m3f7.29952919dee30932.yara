
rule m3f7_29952919dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.29952919dee30932"
     cluster="m3f7.29952919dee30932"
     cluster_size="37"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script redirector html"
     md5_hashes="['06aa5f27dd20d7201cf5497ad46f8b0d','0f03f5fe3400dd5de01541bebdafb13a','82f67c9ceef976085a7c1d7eb8b7faab']"

   strings:
      $hex_string = { 3e33353f537472696e672e66726f6d43686172436f646528632b3239293a632e746f537472696e6728333629297d3b6966282127272e7265706c616365282f5e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
