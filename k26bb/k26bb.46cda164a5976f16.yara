
rule k26bb_46cda164a5976f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.46cda164a5976f16"
     cluster="k26bb.46cda164a5976f16"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack emhuei malicious"
     md5_hashes="['52c4fa81731eec277645296543a9bb7199658643','0b7520e6905c562bc01a81ea8330935499e5ea71','b668c16cbc1e13059f05907e20d048bdc72808dc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.46cda164a5976f16"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
