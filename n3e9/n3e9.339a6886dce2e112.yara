
rule n3e9_339a6886dce2e112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.339a6886dce2e112"
     cluster="n3e9.339a6886dce2e112"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector gate delf"
     md5_hashes="['2b76e655c173135b4639d455fe405a42','3f41c7691d555e83d5397d26a50669b8','ee811845a1e80f88f37d02407a1b437f']"

   strings:
      $hex_string = { b344ad5ffb576ccacddfd05e22889a8ab066a016cccb03918d5090e4f135f2d733c8f6b8d46b73e68128f35284ffeff0045d5abf3a30142faee9fc19fa80c69f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
