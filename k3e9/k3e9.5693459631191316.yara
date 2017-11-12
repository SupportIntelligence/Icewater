import "hash"

rule k3e9_5693459631191316
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5693459631191316"
     cluster="k3e9.5693459631191316"
     cluster_size="4834 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="rincux tdss malicious"
     md5_hashes="['15e49d1fa6bd2693ac22c9133610ddab', '00b9124eca141a011d9ed56c502b2c63', '0da18b98f65894212be6af3de1a56f2a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "3d7758e3950092dead784b9e100cf8ad"
}

