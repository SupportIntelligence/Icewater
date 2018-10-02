
rule o26c0_59e2d0221c9b11b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.59e2d0221c9b11b2"
     cluster="o26c0.59e2d0221c9b11b2"
     cluster_size="346"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious prepscram attribute"
     md5_hashes="['043cf90dc88d8cf06dbe9b93cbd2399e80484dbf','f6ad49f3aee36bc715103acd71f2cc1ca99440b9','3aec77b9b9925485c2c1e54b17802859957ff6d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.59e2d0221c9b11b2"

   strings:
      $hex_string = { 36742d67d37c5d51484b88553bd932f522eed1a6154989be0cda04b44075ec6b1f1d15349aa2af197de4abed6a79e28d442bf8862a356e9dbc9e635b73f7b5d5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
