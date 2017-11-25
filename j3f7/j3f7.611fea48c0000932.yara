
rule j3f7_611fea48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.611fea48c0000932"
     cluster="j3f7.611fea48c0000932"
     cluster_size="20"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html iframeref"
     md5_hashes="['0a2d4c67aa9b76b295c70bc7113d70d1','1623178b984ec2df631751f098a3cebf','cb23f1b99a553ed44f905ceb9c6c9950']"

   strings:
      $hex_string = { 3435207372633d687474703a2f2f6e6d736261736562616c6c2e636f6d2f706f73742e7068703f69643d3636363038383e3c2f696672616d653e3c2f626f6479 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
