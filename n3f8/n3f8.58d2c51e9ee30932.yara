
rule n3f8_58d2c51e9ee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.58d2c51e9ee30932"
     cluster="n3f8.58d2c51e9ee30932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp androidos scamapp"
     md5_hashes="['e134455d7c28ad028924d223fdb1313e71a43edc','26bb250a850d890eb9c2fc7921d22b821dc44e21','610047ff73d04208e9cef058abe80d4af40addea']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.58d2c51e9ee30932"

   strings:
      $hex_string = { 01b3061124000068016702203100006801d2049d3700006801a606263800006901f400712100006901e1047321000069019d05752c000069016409993500006a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
