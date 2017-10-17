import "hash"

rule m3e9_3124da46dec30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3124da46dec30932"
     cluster="m3e9.3124da46dec30932"
     cluster_size="36 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus vbran wbna"
     md5_hashes="['481aa2b2ef3c27ca6dcfe299bc35c40d', '9eb7696b098f809dfcef5777997ce315', '03df0e009f4ba1ee9468040eee5563af']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(123904,1024) == "a328530dc7e9ffdd8f6f21e57e6a9c46"
}

