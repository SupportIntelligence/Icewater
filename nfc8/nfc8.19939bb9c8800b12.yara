
rule nfc8_19939bb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.19939bb9c8800b12"
     cluster="nfc8.19939bb9c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos androidos banker"
     md5_hashes="['239365911d38c2a24249b770f7c87726d4cf49c4','d980d7bfb324fd515e806272171b77e272e29886','f776200e7c02096f9a9b2b5da7845a3ca76e4186']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.19939bb9c8800b12"

   strings:
      $hex_string = { eba731866b09aed5a32830e5256fc1c4bb3874d01b339f7bf945a592f11ab7fb8932f71cbfa2ad14d79d136783d8c5c612c87107e666654c16f49922f3cd8a87 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
