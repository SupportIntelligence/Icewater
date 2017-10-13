import "hash"

rule m3e9_2195a9b4d8caf132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2195a9b4d8caf132"
     cluster="m3e9.2195a9b4d8caf132"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="ckxw delf malicious"
     md5_hashes="['3b0c2ec2b88689e14b059e00e7cfe158', 'edd2ce1f45f67241c3fdc30ef8253dc1', 'f9bd8cbd43e314c7ca2dd3a00e895217']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(11294,1027) == "c5d65ba0f9f89e942663f7732cd2b174"
}

