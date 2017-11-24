
rule m3e9_316338379fbb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338379fbb1112"
     cluster="m3e9.316338379fbb1112"
     cluster_size="292"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['0716b79a102d2180634373d8005ae413','076dedb80198d36a91768fbd6c4eed11','3cca16a8df0b3b5964550a6b5d286226']"

   strings:
      $hex_string = { e1efa454f30aae84888a4418c0326a0f85d991dabdb0452a2d1b941216a363457f41cc028bbc11ad6773b9b87b8082c46897243d17a9710b4ab39e34fb1d4f9f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
