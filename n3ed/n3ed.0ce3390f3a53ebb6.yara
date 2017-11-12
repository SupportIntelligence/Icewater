
rule n3ed_0ce3390f3a53ebb6
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ce3390f3a53ebb6"
     cluster="n3ed.0ce3390f3a53ebb6"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['39b6ca4f6b03d2167317056f7beec845','42040dbd024a2ba42c6c90ec020bbe08','b96514fb2f54f06ef58678da8c6ea8bd']"

   strings:
      $hex_string = { 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
