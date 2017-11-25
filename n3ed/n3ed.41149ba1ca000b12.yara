
rule n3ed_41149ba1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.41149ba1ca000b12"
     cluster="n3ed.41149ba1ca000b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer backdoor"
     md5_hashes="['17fa010fd8d17bf8493141606c14b1e6','6ade280967ff8e7222410f967225d9fa','d011db2115f8d29edf3de6cad8003406']"

   strings:
      $hex_string = { a29550090531c1c83cf76219d7d9c55dbbbeabd5c9c625a0e16ee0dbd69d5ffe5c136f3fb4aebac7902d559029f3494634354f882942d21cb5564841e9d044f5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
