import "hash"

rule m3e9_692596c9cc001932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692596c9cc001932"
     cluster="m3e9.692596c9cc001932"
     cluster_size="13240 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="pyllb virut malicious"
     md5_hashes="['04b993a36ea095ab612764c21b451802', '099d31cd241271b81303301f0d9472f9', '049828ec823780d789b02ff9f9176451']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(35840,1024) == "a718ea09e8047dea3a2daa605977f31c"
}

