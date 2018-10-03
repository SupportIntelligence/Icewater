
rule m231b_299a3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.299a3949c0000b12"
     cluster="m231b.299a3949c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['bcae1a452879e478b088165a99aca77b3a6edb64','e3549461063a8524f6781e07d746c0588317c3d8','80c666c40bd5006bb5fcea8ca8d252fa166ba1a0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.299a3949c0000b12"

   strings:
      $hex_string = { 6e643a236666662075726c28687474703a2f2f342e62702e626c6f6773706f742e636f6d2f2d355f306c454a69644656512f547577306f31576d4d43492f4141 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
