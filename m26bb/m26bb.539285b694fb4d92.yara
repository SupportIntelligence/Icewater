
rule m26bb_539285b694fb4d92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.539285b694fb4d92"
     cluster="m26bb.539285b694fb4d92"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="swisyn malicious riskware"
     md5_hashes="['3431c55dbe666440b468f4b914bbf2881aec0373','ba74ce292abef7a74d2fcb5ec1858da71b0966c8','a188babf1ce3d4dfa1fa8f2ed7b4dcf6caad2fb0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.539285b694fb4d92"

   strings:
      $hex_string = { 6f6300100248656170416c6c6f6300160248656170467265650000d70252746c556e77696e640094035769646543686172546f4d756c746942797465007f0147 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
