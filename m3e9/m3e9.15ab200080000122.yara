
rule m3e9_15ab200080000122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.15ab200080000122"
     cluster="m3e9.15ab200080000122"
     cluster_size="46"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor lolbot strictor"
     md5_hashes="['04c36e3f4bd168e603d611c539490937','06c6a886be97fd03eb894a6e58d6a4fc','a5b724df6c8db221f79e9c781291c29a']"

   strings:
      $hex_string = { 00750583c8ffeb0d8b45f40fb704788b55f80342105f5e5b89ec5dc20800908d7c27005356578b4424108b54241489c189cb66813b4d5a740431c0eb448b433c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
