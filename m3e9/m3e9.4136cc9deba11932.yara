import "hash"

rule m3e9_4136cc9deba11932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4136cc9deba11932"
     cluster="m3e9.4136cc9deba11932"
     cluster_size="247 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy linkury toolbar"
     md5_hashes="['809ccb81e00f9ed7e08a29db90132b1c', 'efd99629db65ffbe9195a8e081cb61fe', '78de63cdc557f06fae417b6981c80a86']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(156160,1024) == "e14050388cd96c7e05ed86b0160f0fb8"
}

