
rule n3e9_339a6886dccad115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.339a6886dccad115"
     cluster="n3e9.339a6886dccad115"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector gate aovhryb"
     md5_hashes="['01424e0d6ca2c89d7416a8e6cae1f0a7','7d222e95eb4753158aea1396b059106b','f84706aef987db4f80aa5be15ff68dd6']"

   strings:
      $hex_string = { b344ad5ffb576ccacddfd05e22889a8ab066a016cccb03918d5090e4f135f2d733c8f6b8d46b73e68128f35284ffeff0045d5abf3a30142faee9fc19fa80c69f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
