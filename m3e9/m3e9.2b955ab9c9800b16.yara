
rule m3e9_2b955ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b955ab9c9800b16"
     cluster="m3e9.2b955ab9c9800b16"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['3088e209b148af5833411bb37fda609d','503eb1f7d99d94a05fcb6c8d1a457ac1','eef8722fae17e50942d120398f8d710c']"

   strings:
      $hex_string = { d08ad988d16701aa90578c9c72a4e9dd3fc2c78bc1ab48eb0bba32a340f57c094276951cd8fae270ceeed37af226894bfc74cdfba9a55efe03525ef71bedbb24 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
