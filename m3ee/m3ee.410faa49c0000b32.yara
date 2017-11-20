
rule m3ee_410faa49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ee.410faa49c0000b32"
     cluster="m3ee.410faa49c0000b32"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer fixflo"
     md5_hashes="['03d926ba8e39c2b9c0b9e56c86426afe','041215a22967b014747aa940786f4582','9e8121c04ca7b15890c383fdeffe7009']"

   strings:
      $hex_string = { a29550090531c1c83cf76219d7d9c55dbbbeabd5c9c625a0e16ee0dbd69d5ffe5c136f3fb4aebac7902d559029f3494634354f882942d21cb5564841e9d044f5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
