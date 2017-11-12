
rule n3e9_55945ec1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.55945ec1c4000932"
     cluster="n3e9.55945ec1c4000932"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virtob virut pornoblocker"
     md5_hashes="['23dce2f117d8f8792ecb6a4a88d0c91c','300f4bd65380cd38d9b694b5b2167d10','9542516a43c872bad72613bf7c7e0e03']"

   strings:
      $hex_string = { 109d26505212d5ebfe3b006be9ededb1bfbb9b57120aa356ab31373fc70b9f3cc3e73fdfa4d36938ff3b119b9b3bbcf7de55debb7c83b72fdee4951f6cb2b91d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
