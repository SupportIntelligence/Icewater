
rule n3e9_351e94a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.351e94a9c8800b12"
     cluster="n3e9.351e94a9c8800b12"
     cluster_size="35"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot japik bublik"
     md5_hashes="['007e066fe3b8b9a97c0a045bd7c96556','0885caa98d31b187b6e594d9665a4180','bc2eea458c861b848fceab9584e0272b']"

   strings:
      $hex_string = { ce0371231485ad077c13e3d728c199367941db92b66f944a49fe767fcc4eda65e0e7d231fcff12b483ffd41a7b415b018683eb1904273d221b7adf18e60fea43 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
