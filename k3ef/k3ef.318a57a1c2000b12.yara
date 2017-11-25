
rule k3ef_318a57a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.318a57a1c2000b12"
     cluster="k3ef.318a57a1c2000b12"
     cluster_size="9"
     filetype = "PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet browsefox malicious"
     md5_hashes="['18cab271b950597a6e26ab55bc1cb81f','1e0a53683b4e8e4307e0681786a18555','ec9a117bf8a1612034557fd8fc7cb029']"

   strings:
      $hex_string = { 5469746c652822446f744e65745a697020534658204172636869766522295d0a00005b617373656d626c793a2053797374656d2e5265666c656374696f6e2e41 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
