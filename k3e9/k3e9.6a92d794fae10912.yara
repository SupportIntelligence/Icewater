
rule k3e9_6a92d794fae10912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92d794fae10912"
     cluster="k3e9.6a92d794fae10912"
     cluster_size="111"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis malicious"
     md5_hashes="['02937f06fde736598e6b7d2b0e08130d','0545ef01ec6e5308cb8dfd675193479c','2d2299ed4c39fe5212842dac67c4c268']"

   strings:
      $hex_string = { 45e82bc73bd87e028bd83b5de07d088b5de0eb0383c31433c06a01505053ff75fc50ff7508ff15d84000105f5e5bc9c351515355568b742418578b3dc4400010 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
