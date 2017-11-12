import "hash"

rule m3ed_531403b999446916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999446916"
     cluster="m3ed.531403b999446916"
     cluster_size="155 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a573c3b76043b8e4cc05d4f620c0b4cf', 'b6e212e1d305657c8a1d444c9863962f', 'c2fdaaf866df22d5e69e542b55075355']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

