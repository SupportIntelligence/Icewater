import "hash"

rule n3e9_611453e1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.611453e1c4000932"
     cluster="n3e9.611453e1c4000932"
     cluster_size="14903 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="zusy backdoor shiz"
     md5_hashes="['0aabdd7c697ea7da240e637faf68f373', '07f572f87b9eb0d48d9c17143ab2a79c', '0510b1a3af861e5463cfc7133473ffe7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(30720,1024) == "78e408c2e6fd82825e34dc166b849072"
}

