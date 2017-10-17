import "hash"

rule n3e9_3619b41dc6620b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3619b41dc6620b14"
     cluster="n3e9.3619b41dc6620b14"
     cluster_size="334 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="auslogics unwanted gkrbja"
     md5_hashes="['1f6666641fcb74da7f1716b3e340c1d0', '74b20fa65b8de966d275f262f45c5adb', '3494891baebb8df2c37c7706abee39e5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(349696,1024) == "538363a4ea0fef632324399081c25270"
}

