import "hash"

rule o3e9_131e1ce9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.131e1ce9c8800912"
     cluster="o3e9.131e1ce9c8800912"
     cluster_size="99 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt clej eyestye"
     md5_hashes="['aaa77761077f9d77828b071ce03659c0', 'da2acc92846c018795da97376bf069fc', 'ac96c702bacb55ba775eeaab3b4258ae']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1558528,1024) == "be442c9bc0d2d368187370d83ed491fd"
}

