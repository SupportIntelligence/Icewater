
rule j3f8_7866b6b0189b1130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7866b6b0189b1130"
     cluster="j3f8.7866b6b0189b1130"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="shedun abfd androidos"
     md5_hashes="['8a85053b6ab816dcb398a70c62a875d14b9fbf47','aaa7ca068aa459bf343485a8ca81f96314bb3d11','36e07c78a28dbf363522803e7ca0b9f65e9ca017']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.7866b6b0189b1130"

   strings:
      $hex_string = { 063c696e69743e000c417070426173655468656d6500084170705468656d6500054445425547000344455300144445532f4543422f504b43533550414444494e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
