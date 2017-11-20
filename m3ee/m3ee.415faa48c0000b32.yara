
rule m3ee_415faa48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ee.415faa48c0000b32"
     cluster="m3ee.415faa48c0000b32"
     cluster_size="29"
     filetype = "PE32 executable (DLL) (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer fixflo"
     md5_hashes="['02d7e1d69bc8f0d0c9138c509d2a948a','0ab469eee7116caa3e425353a6d2bb73','918d80b356a5895228d5a1a624e322a4']"

   strings:
      $hex_string = { a29550090531c1c83cf76219d7d9c55dbbbeabd5c9c625a0e16ee0dbd69d5ffe5c136f3fb4aebac7902d559029f3494634354f882942d21cb5564841e9d044f5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
