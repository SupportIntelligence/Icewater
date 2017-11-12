import "hash"

rule n3e9_39ca96e9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39ca96e9c8800932"
     cluster="n3e9.39ca96e9c8800932"
     cluster_size="179 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy backdoor finfish"
     md5_hashes="['ccaad9ba854f262b3b7ed75ef5c487ff', '4ca315b24eb60a8c1a25669d88551b71', '81c67f1d2fa9c1893bf89bd1ab9c6f3f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(379089,1035) == "01c05ca425fa4726baa4ec090d888bae"
}

