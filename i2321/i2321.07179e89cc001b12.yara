
rule i2321_07179e89cc001b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.07179e89cc001b12"
     cluster="i2321.07179e89cc001b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['48c7e0b5cc919d84794ace3d10b3e1a5','4b42a4fb532e3613ed4137878f3f3dab','a8bedc36bee34a44abec8c8fda79a450']"

   strings:
      $hex_string = { 576f9e2985a9c9d1898d78bd7ba2f2c2f862a571b158ae2d56462fc49ecb69ec9938bbe3958b69e0f048314e70a3c55a9c711cebe87c6db6d24817125b4c1e1b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
