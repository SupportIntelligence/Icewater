
rule k3e7_35b4b51cc2211912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.35b4b51cc2211912"
     cluster="k3e7.35b4b51cc2211912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod trojandropper malicious"
     md5_hashes="['1347bd0d177a42ba70b73a31cd1fce98','ab6e026d7a90e7b17428240c3cb607d4','ab6e026d7a90e7b17428240c3cb607d4']"

   strings:
      $hex_string = { e4196b434720e7808dd21a1b44fd0e9b17c7da425813f7619e047638a295ea626c6f1e6a01e3fe2ddff0c422e8857dd3a5087ee802003ff4db1dfb9c102a3e39 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
