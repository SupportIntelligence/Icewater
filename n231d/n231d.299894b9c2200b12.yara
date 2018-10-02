
rule n231d_299894b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.299894b9c2200b12"
     cluster="n231d.299894b9c2200b12"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bankbot androidos hqwar"
     md5_hashes="['7e4aa0e38f2ffbbbaa14cae68e8bb1c0bc5826ca','28aff62b40dac1e6af39ce19d1558273068f6a74','13a2f7edd0b04bf6ed35ec019a0262dd1a4a9464']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.299894b9c2200b12"

   strings:
      $hex_string = { 2afbe8a77c22ecd21c24b07e7bd61386153271811620f6494cf9a29abf41971d334df7baf539c3f83893a079d859d1f36894cf6650d5146764b53cb7084503ae }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
