import "hash"

rule n3e9_29c65164ea208b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c65164ea208b12"
     cluster="n3e9.29c65164ea208b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crypt cuegoe trojandropper"
     md5_hashes="['d7e834aa77a88c85a2cf16ef9015adb2', '1f5442a0696449a66db7b62b37a85720', 'd7e834aa77a88c85a2cf16ef9015adb2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(532460,1028) == "00fc4f62daf0da374568acfeb55d7e7f"
}

