
rule n2321_331a9299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.331a9299c2200b12"
     cluster="n2321.331a9299c2200b12"
     cluster_size="61"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="solimba strictor morstar"
     md5_hashes="['07ba2c1cc00be630f0cdce8869b5eab7','09b6636367c5ab0a78dec3accf378278','4e02b2cd2a4d4724d59db895d6af4bd0']"

   strings:
      $hex_string = { 7571a47c4fe2d749cedfdcd37ba81908c27afccfef80d08797967fff9806bc4b53d13d9b864430d2bb641e39183288c3366f17bf9c78e6b1b2b872952979e4d6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
