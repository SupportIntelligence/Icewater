import "hash"

rule n3e9_09119822dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.09119822dabb0932"
     cluster="n3e9.09119822dabb0932"
     cluster_size="31227 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="vbkrypt qmlfrt injector"
     md5_hashes="['01c5a142c56ef965839f8d77841b6fcf', '048052d7f5101abdbdab0c924b0a733e', '003bb0a324baee48426e2efd3ddfe412']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(675328,1024) == "a1be46156b309e19555123e406941dcc"
}

