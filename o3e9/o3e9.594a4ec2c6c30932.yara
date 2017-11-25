
rule o3e9_594a4ec2c6c30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a4ec2c6c30932"
     cluster="o3e9.594a4ec2c6c30932"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply riskware malicious"
     md5_hashes="['0052e1e15c02ee47d5bb90092f4dee25','1d850cd61aaa586b970f26b83c33ec1e','fc4ffc820874445efa6a3aefe530d166']"

   strings:
      $hex_string = { 0072002000270025007300270020006e006f007400200066006f0075006e006400050041007000720069006c0003004d006100790004004a0075006e00650004 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
