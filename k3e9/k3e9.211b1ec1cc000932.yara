
rule k3e9_211b1ec1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.211b1ec1cc000932"
     cluster="k3e9.211b1ec1cc000932"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart genericrxbm"
     md5_hashes="['1244f0c6d05edf46a3e5b8c0492ff411','747a25977bd4ff41852edabff340b361','ea87953253a3aa796323c8b9b2decf55']"

   strings:
      $hex_string = { ee1646b56d31e3becf97866b3635a1ecf676222e0e3ec2db51e9b0921713f371a4b77790999594825c14eb5ffc5eb1981e09c3967d247a21d9a31ec0fbe89c87 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
