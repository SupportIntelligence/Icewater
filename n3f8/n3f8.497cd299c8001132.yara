
rule n3f8_497cd299c8001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.497cd299c8001132"
     cluster="n3f8.497cd299c8001132"
     cluster_size="220"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="sandr androidos kasandra"
     md5_hashes="['aebae87dca25820c1ac5c3fa83eb7e00d2aceeda','5e75d53a19eb0ebc1c69f1cc82aaeafa76dd6c93','6c21409b1ff6ad91b6ac46daf4fd7f9230d70652']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.497cd299c8001132"

   strings:
      $hex_string = { 04b1431504b4426e20830048006e10060307000a047b448244527553011506803fc6657f558226c8656e3085004805547432016e3059023402547232016e205c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
