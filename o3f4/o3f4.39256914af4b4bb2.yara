import "hash"

rule o3f4_39256914af4b4bb2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f4.39256914af4b4bb2"
     cluster="o3f4.39256914af4b4bb2"
     cluster_size="2910 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="linkury zusy malicious"
     md5_hashes="['08ab2077111ec4c413cf67ce76630ae0', '06224349d025e12887eb0285c0181a0d', '092755bdbbaf74c0867643721f50a71b']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3778048,1536) == "e44a8100134469251cf764639a9ff791"
}

