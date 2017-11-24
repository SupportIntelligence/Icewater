
rule k2321_2354ecedb2664aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2354ecedb2664aba"
     cluster="k2321.2354ecedb2664aba"
     cluster_size="5"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['4ff8ae327aecea0cb9a89607d072551d','55c4667c25bb0c477b4a72fcf2692405','d7ad75957e4312eb625ab9d40a8b707f']"

   strings:
      $hex_string = { b5ccd24a43a3ed7c7a17ac91582018b883f7e2746b26b2c611af7ebef566f46bffc9cfe149ad3b7f964ebcd0398d78a5731af1922e6d697bdaae8e3523c9b60f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
