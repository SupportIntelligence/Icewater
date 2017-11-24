
rule m3e9_266f86decab1d312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.266f86decab1d312"
     cluster="m3e9.266f86decab1d312"
     cluster_size="212"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['04c41c56f57d71f6ac828349c16253b2','04d7a14453e1fd7985242770c4eaac47','155f09ce4b95850d0da8f090e41cfdc1']"

   strings:
      $hex_string = { 540d5ce48d93ea798338276218c6fb4e56d48fb2ac1a42ff84e3e796539b8b300f6b49f99e687eb9b6b7a88ac14321827ff305598e6588ed907bd89ec85b87f7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
