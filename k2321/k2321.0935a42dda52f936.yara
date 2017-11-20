
rule k2321_0935a42dda52f936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0935a42dda52f936"
     cluster="k2321.0935a42dda52f936"
     cluster_size="41"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre wapomi"
     md5_hashes="['01dcd22619f044d5257eaf0484932953','094c66fd958a76607788b76d1769d28b','76745391d8409f330a24511245e72cd4']"

   strings:
      $hex_string = { 3c8dfe5b24b30d5dc710da65ceb71efad3e4143b3dad3592dd2e33dda46f0267a5d63731db13f0811bdfaf05f9887977f2a7bc7e7fa980296b9a34e3cced0cbf }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
